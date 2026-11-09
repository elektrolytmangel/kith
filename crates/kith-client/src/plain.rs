//! Incoming application and plain messages, sync answers.

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    pub(crate) fn handle_app(
        &mut self,
        org: String,
        group: String,
        from: String,
        ct: &[u8],
    ) -> Result<Handled, ClientError> {
        // A sender at an older epoch missed commits: send them along (REQ-ENC-002).
        // The epoch is the message's unauthenticated header, so only for a member of
        // the group, and once per our epoch (it can still ask with `CommitRequest`).
        let help = match (Groups::message_epoch(ct), self.groups.epoch(&group)) {
            (Ok(theirs), Ok(ours))
                if theirs < ours
                    && self.trusted_member(&org, &group, &from)
                    && self.helped.get(&(group.clone(), from.clone())) != Some(&ours) =>
            {
                self.helped.insert((group.clone(), from.clone()), ours);
                self.serve_commits(org.clone(), group.clone(), from.clone(), theirs)?
                    .replies
            }
            _ => vec![],
        };
        let mut handled = match self.groups.decrypt(&group, ct) {
            Ok(d) if d.sender.to_hex() == from => {
                self.handle_plain(org, group, from, &d.plaintext)?
            }
            Ok(_) => Handled::event(Event::Rejected {
                org,
                from,
                reason: "MLS sender does not match the relay's sender".into(),
            }),
            Err(GroupError::EpochGap { local, .. }) => self.behind(org, group, from, local),
            Err(e) => {
                // A member's message for our own epoch that we cannot read means we
                // are on different branches of a fork: ask for its commits, which
                // start one epoch back and show the fork.
                let probe = self.same_epoch_member(&group, &from, ct);
                let mut h = Handled::event(Event::Rejected {
                    org: org.clone(),
                    from: from.clone(),
                    reason: e.to_string(),
                });
                if let Some(local) = probe {
                    h.replies.push(direct(
                        &org,
                        &from,
                        sync::outer_body(&Outer::CommitRequest {
                            group,
                            epoch: local,
                        }),
                    ));
                }
                h
            }
        };
        // Commits first, so the peer can read the encrypted replies that follow.
        handled.replies.splice(0..0, help);
        Ok(handled)
    }

    /// Our epoch, if `ct` is for it and `from` is a member of our view of the group.
    pub(crate) fn same_epoch_member(&self, org: &str, from: &str, ct: &[u8]) -> Option<u64> {
        let local = self.groups.epoch(org).ok()?;
        let member = self
            .groups
            .members(org)
            .ok()?
            .iter()
            .any(|d| d.to_hex() == from);
        (member && Groups::message_epoch(ct).ok()? == local).then_some(local)
    }

    /// `scope`: the group the message was encrypted for, which is also the scope
    /// its data belongs to.
    pub(crate) fn handle_plain(
        &mut self,
        org: String,
        scope: String,
        from: String,
        plaintext: &[u8],
    ) -> Result<Handled, ClientError> {
        use sync::Message;
        let rejected = |reason: String| {
            Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason,
            })
        };
        let msg = match sync::parse(plaintext) {
            Ok(m) => m,
            Err(e) => return Ok(rejected(e)),
        };
        match msg {
            Message::Change(change) if change.body.scope.as_str() != scope => {
                Ok(rejected("change belongs to another scope".into()))
            }
            Message::Change(change) => match self.receive(change.clone()) {
                Ok(is_new) => Ok(Handled {
                    replies: if is_new {
                        self.eager_fetch(&org, &change)?
                    } else {
                        vec![]
                    },
                    event: Event::Received {
                        org,
                        from,
                        change: Box::new(change),
                        is_new,
                    },
                }),
                Err(ClientError::Rejected(e)) => Ok(rejected(e.to_string())),
                Err(ClientError::Forbidden(e)) => Ok(rejected(e)),
                Err(e) => Err(e),
            },
            Message::ChunkWant(ids) => {
                let (replies, sent, missing) = self.serve_chunks(&org, &scope, &from, &ids)?;
                Ok(Handled {
                    replies,
                    event: Event::ChunksServed {
                        to: from,
                        sent,
                        missing,
                    },
                })
            }
            Message::Chunks(chunks) => {
                let (stored, ready) = self.absorb_chunks(&scope, chunks)?;
                Ok(Handled::event(Event::FileChunks {
                    from,
                    stored,
                    ready,
                }))
            }
            Message::ChunkMissing(ids) => {
                // The peer the relay picked may not have the file: ask its author.
                let replies = self.ask_authors(&org, &scope, &from, &ids)?;
                Ok(Handled {
                    replies,
                    event: Event::ChunksMissing {
                        from,
                        count: ids.len(),
                    },
                })
            }
            Message::Query(query) => {
                match kith_sync::respond(&self.store.scope_ids(&org_scope(&scope)?)?, &query) {
                    Ok(answer) => {
                        let mut replies = vec![direct(
                            &org,
                            &from,
                            self.app_body(&scope, &sync::reply_body(&answer))?,
                        )];
                        // Catching up also hands over the notices we hold, so a
                        // new admin or always-on client learns them (ADR 0024).
                        if scope == org {
                            let held: Vec<String> = self
                                .revocations
                                .iter()
                                .filter(|r| r.org.to_hex() == org)
                                .map(Revocation::to_hex)
                                .collect();
                            for body in sync::notices_bodies(&held) {
                                replies.push(direct(&org, &from, self.app_body(&scope, &body)?));
                            }
                        }
                        Ok(Handled {
                            replies,
                            event: Event::SyncServed { from },
                        })
                    }
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Message::More => {
                // Another round with this peer (REQ-SYNC-005), unless one is running.
                if self.reconciling.contains_key(&scope) {
                    return Ok(Handled::event(Event::Ignored));
                }
                let body = self.start_reconcile(&scope, Some(&from))?;
                Ok(Handled {
                    replies: vec![direct(&org, &from, body)],
                    event: Event::Ignored,
                })
            }
            Message::Notices(lines) if scope == org => {
                self.learn_notices(&org, &lines)?;
                Ok(Handled::event(Event::Ignored))
            }
            Message::Notices(_) => Ok(rejected("notices belong to the org group".into())),
            Message::Reply(answer) => {
                let Some((r, peer)) = self.reconciling.get_mut(&scope) else {
                    // Not reconciling (any more): a late or duplicate answer.
                    return Ok(Handled::event(Event::Ignored));
                };
                // One reconciliation runs with one peer: the first to answer, or the
                // one we asked. Another member's answer would derail it.
                match peer {
                    Some(p) if *p != from => return Ok(Handled::event(Event::Ignored)),
                    Some(_) => {}
                    None => *peer = Some(from.clone()),
                }
                match r.step(&answer) {
                    Ok(kith_sync::Step::Continue(query)) => Ok(Handled {
                        replies: vec![direct(
                            &org,
                            &from,
                            self.app_body(&scope, &sync::query_body(&query))?,
                        )],
                        event: Event::Ignored,
                    }),
                    Ok(kith_sync::Step::Done(diff)) => {
                        self.reconciling.remove(&scope);
                        let (to_send, cut) = batch(self.changes_for(&scope, &diff.to_send)?);
                        // Ask for one batch; the peer sends `More` if it has further
                        // changes for us after answering.
                        let to_request =
                            &diff.to_request[..diff.to_request.len().min(SYNC_BATCH_CHANGES)];
                        let mut replies = if to_send.is_empty() && to_request.is_empty() {
                            vec![]
                        } else {
                            self.offer_frames(&org, &scope, &from, to_request, &to_send)?
                        };
                        if cut {
                            replies.push(self.more_frame(&org, &scope, &from)?);
                        }
                        Ok(Handled {
                            event: Event::SyncCompared {
                                from,
                                sending: to_send.len(),
                                wanting: to_request.len(),
                            },
                            replies,
                        })
                    }
                    Err(e) => {
                        self.reconciling.remove(&scope);
                        Ok(rejected(e.to_string()))
                    }
                }
            }
            Message::Offer { want, changes } => {
                let (mut stored, mut known, mut rejected_n) = (0, 0, 0);
                let mut fetches = vec![];
                for enc in changes {
                    let change = match kith_store::codec::decode_change(&enc) {
                        Ok(c) => c,
                        Err(_) => {
                            rejected_n += 1;
                            continue;
                        }
                    };
                    if change.body.scope.as_str() != scope {
                        rejected_n += 1;
                        continue;
                    }
                    match self.receive(change.clone()) {
                        Ok(true) => {
                            stored += 1;
                            fetches.extend(self.eager_fetch(&org, &change)?);
                        }
                        Ok(false) => known += 1,
                        Err(ClientError::Rejected(_) | ClientError::Forbidden(_)) => {
                            rejected_n += 1
                        }
                        Err(e) => return Err(e),
                    }
                }
                // Reply only if asked, so two offers never ping-pong forever.
                let mut replies = if want.is_empty() {
                    vec![]
                } else {
                    let (wanted, cut) = batch(self.changes_for(&scope, &want)?);
                    let mut r = self.offer_frames(&org, &scope, &from, &[], &wanted)?;
                    // The asker cut its list at one batch, or we cut our answer:
                    // tell it to reconcile again.
                    if cut || want.len() >= SYNC_BATCH_CHANGES {
                        r.push(self.more_frame(&org, &scope, &from)?);
                    }
                    r
                };
                replies.extend(fetches);
                Ok(Handled {
                    event: Event::SyncReceived {
                        from,
                        stored,
                        known,
                        rejected: rejected_n,
                        requested: want.len(),
                    },
                    replies,
                })
            }
        }
    }

    /// The stored changes of `org`'s scope with these IDs (unknown IDs and other
    /// scopes are skipped), oldest first. Includes changes the policy rejects: the
    /// peer must see them to reject them (and their dependents) too.
    pub(crate) fn changes_for(
        &self,
        scope: &str,
        ids: &[ChangeId],
    ) -> Result<Vec<Change>, ClientError> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(c) = self.store.get(id)?
                && c.body.scope.as_str() == scope
            {
                out.push(c);
            }
        }
        out.sort_by_key(|c| (c.body.timestamp_ms, c.change_id));
        Ok(out)
    }

    pub(crate) fn more_frame(
        &mut self,
        org: &str,
        scope: &str,
        to: &str,
    ) -> Result<Frame, ClientError> {
        Ok(direct(org, to, self.app_body(scope, &sync::more_body())?))
    }

    pub(crate) fn offer_frames(
        &mut self,
        org: &str,
        scope: &str,
        to: &str,
        want: &[ChangeId],
        changes: &[Change],
    ) -> Result<Vec<Frame>, ClientError> {
        sync::offer_bodies(want, changes)
            .into_iter()
            .map(|inner| Ok(direct(org, to, self.app_body(scope, &inner)?)))
            .collect()
    }
}
