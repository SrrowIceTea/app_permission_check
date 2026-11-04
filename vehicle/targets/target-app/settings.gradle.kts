// Phase 2 靶子 App —— 仅用于授权测试（自有设备与自有 APK）。
// 仓库顺序有意为之：dl.google.com / mavenCentral 在本机被网络阻断，
// 阿里云镜像完整代理 Google Maven 与中央仓库；后面的上游条目仅作兜底，
// 预期永远不会被访问。构建卡住时先删兜底条目，而不是切换版本。
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

rootProject.name = "vscanner-target-app"
include(":app")
if (providers.gradleProperty("aaidFixture").orNull == "true") include(":aaid-fixture")
