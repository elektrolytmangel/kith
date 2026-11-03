plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

android {
    namespace = "dev.kith"
    compileSdk = 35
    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    publishing { singleVariant("release") { withSourcesJar() } }
}

dependencies {
    // UniFFI-generated code calls native code through JNA.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = project.group.toString()
            artifactId = "kith-android"
            version = project.version.toString()
            afterEvaluate { from(components["release"]) }
        }
    }
    repositories {
        // Default: GitHub Packages of this repository. Override with -PmavenUrl=...
        maven {
            name = "target"
            url = uri(
                (findProperty("mavenUrl") as String?)
                    ?: "https://maven.pkg.github.com/${System.getenv("GITHUB_REPOSITORY") ?: "OWNER/kith"}"
            )
            credentials {
                username = System.getenv("MAVEN_USERNAME") ?: System.getenv("GITHUB_ACTOR")
                password = System.getenv("MAVEN_PASSWORD") ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
