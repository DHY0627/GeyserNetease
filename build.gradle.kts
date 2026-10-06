plugins {
    id("java")
    id("com.gradleup.shadow") version "9.4.1"
}

group = "nc.geyserext"
version = "1.1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
    maven("https://repo.opencollab.dev/main/")
    maven("https://repo.opencollab.dev/maven-snapshots/")
}

dependencies {
    // Geyser core — provided by the Geyser platform at runtime (Geyser 2.11.3)
    compileOnly("org.geysermc.geyser:core:2.11.3-SNAPSHOT") {
        exclude(group = "com.google.code.gson", module = "gson")
        exclude(group = "org.cloudburstmc.netty", module = "netty-transport-raknet")
    }

    // Protocol library — provided by Geyser at runtime
    compileOnly("org.cloudburstmc.protocol:common:3.0.0.Beta13-20260917.001841-27")
    compileOnly("org.cloudburstmc.protocol:bedrock-codec:3.0.0.Beta13-20260917.001841-27")
    compileOnly("org.cloudburstmc.protocol:bedrock-connection:3.0.0.Beta13-20260917.001841-27")

    // RakNet / Netty — provided by Geyser at runtime
    compileOnly("org.cloudburstmc.netty:netty-transport-raknet:2.0.0.CR3-20260916.135337-10")
    compileOnly("io.netty:netty-transport:4.2.7.Final")
    compileOnly("io.netty:netty-buffer:4.2.7.Final")
    compileOnly("io.netty:netty-codec:4.2.7.Final")
    compileOnly("io.netty:netty-common:4.2.7.Final")
    compileOnly("io.netty:netty-handler:4.2.7.Final")
    compileOnly("com.google.code.gson:gson:2.10.1")
    compileOnly("it.unimi.dsi:fastutil:8.5.12")
    compileOnly("org.cloudburstmc.math:immutable:2.0")

    // Bundled into shadowJar (implementation)
    implementation("org.yaml:snakeyaml:2.2")
    implementation("com.fasterxml.jackson.core:jackson-annotations:2.17.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.0")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.0")
    implementation("org.bitbucket.b_c:jose4j:0.9.4")
}

tasks.shadowJar {
    archiveFileName = "GeyserNeteaseExtension.jar"
    dependencies {
        include(dependency("org.yaml:snakeyaml:2.2"))
        include(dependency("com.fasterxml.jackson.core:jackson-databind:2.17.0"))
        include(dependency("com.fasterxml.jackson.core:jackson-annotations:2.17.0"))
        include(dependency("com.fasterxml.jackson.core:jackson-core:2.17.0"))
        include(dependency("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.0"))
        include(dependency("org.bitbucket.b_c:jose4j:0.9.4"))
    }
    // Strip dependency license files and service descriptors (not needed at runtime)
    exclude("META-INF/LICENSE", "META-INF/NOTICE", "META-INF/*LICENSE*", "META-INF/*NOTICE*",
        "META-INF/thirdparty-LICENSE", "META-INF/maven/**", "META-INF/services/**")
    relocate("com.fasterxml.jackson", "nc.geyserext.shaded.jackson")
    relocate("org.yaml.snakeyaml", "nc.geyserext.shaded.yaml")
    relocate("org.jose4j", "nc.geyserext.shaded.jose4j")
}
