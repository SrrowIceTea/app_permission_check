// 移动隐私演示夹具 —— 仅用于授权测试（自有设备与自有 APK）。
// 仓库顺序照抄 phase2/target-app：dl.google.com 在本机被阻断，阿里云镜像完整代理
// Google Maven 与中央仓库；后面的上游条目仅作兜底，预期永远不会被访问。
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

rootProject.name = "vscanner-privacy-demo"
include(":app")
