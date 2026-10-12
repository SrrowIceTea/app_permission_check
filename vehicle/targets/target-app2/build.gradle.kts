// 根构建文件。版本矩阵按项目已验证组合固定（Gradle 8.13 · AGP 8.11.1 ·
// Kotlin 2.2.0 · compileSdk 36 · minSdk 29 · targetSdk 35 · JDK 21 · JVM target 17），
// 不允许擅自替换。本夹具不需要 KSP（无 Room / 注解处理），故不引入。
plugins {
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.0" apply false
}
