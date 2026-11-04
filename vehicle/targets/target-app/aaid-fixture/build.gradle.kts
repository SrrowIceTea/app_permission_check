// 仅用于授权测试。 Independent ordinary application for the device AAID check.
plugins { id("com.android.application") }

android {
    namespace = "com.vscanner.aaidprobe"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.vscanner.aaidprobe"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1"
    }
    flavorDimensions += "adIdPermission"
    productFlavors {
        create("declared") { dimension = "adIdPermission" }
        create("omitted") {
            dimension = "adIdPermission"
            applicationIdSuffix = ".omitted"
        }
    }
}

dependencies { implementation("com.google.android.gms:play-services-ads-identifier:18.2.0") }
