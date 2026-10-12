import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.vscanner.rules"

    // android-36 is the only installed platform that ships optional/android.car.jar,
    // which useLibrary below resolves against. android-37.0 would not work either:
    // AGP looks for "platforms/android-37" and the directory is named "android-37.0".
    compileSdk = 36

    // Pinned to an already-installed version on purpose. Left to its default, AGP
    // would try to fetch build-tools from dl.google.com, which is unreachable here.
    buildToolsVersion = "36.0.0"

    // Must come after compileSdk. Resolves platforms/android-36/optional/android.car.jar
    // via optional.json. This is compile-time only - no android.car API is called in
    // Phase 1, and no <uses-library> is declared, so nothing can fail at install time.
    useLibrary("android.car")

    defaultConfig {
        applicationId = "com.vscanner.rules"
        // Room 2.8.5 requires minSdk >= 23. The audit target device is API 35.
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

kotlin {
    compilerOptions {
        // Must stay in step with compileOptions above.
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

ksp {
    // Produces app/schemas/com.vscanner.rules.RulesDatabase/1.json, which
    // tools/verify_schema_parity.py compares against schema.sql.
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    // Brings lifecycleScope, used to run the suspend DAO off the main thread.
    implementation(libs.androidx.lifecycle.runtime.ktx)

    implementation(libs.androidx.room.runtime)
    ksp(libs.androidx.room.compiler)

    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.core)
}
