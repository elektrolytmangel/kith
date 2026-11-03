plugins {
    id("com.android.library")
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
    publishing { singleVariant("release") { withSourcesJar() } }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
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
    // Releases ship the AAR as a GitHub Release asset. To try it in another
    // project locally: `./gradlew publishToMavenLocal`, then add mavenLocal().
}
