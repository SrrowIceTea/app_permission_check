// Repository order is deliberate. dl.google.com and android.googlesource.com are
// unreachable from this network, and Google Maven hosts AGP, AndroidX and Room.
// Aliyun mirrors them completely; the upstream entries are fallbacks only and
// are expected never to be contacted. If a build stalls, remove the fallbacks first.
pluginManagement {
    repositories {
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
    }
}

rootProject.name = "vscanner"
include(":app")
