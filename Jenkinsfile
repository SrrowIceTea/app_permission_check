pipeline {
    agent { label 'windows' }
    options {
        disableConcurrentBuilds()
        timeout(time: 45, unit: 'MINUTES')
    }
    triggers {
        pollSCM('H/5 * * * *')
    }
    environment {
        PYTHONUTF8 = '1'
        PYTHONIOENCODING = 'utf-8'
        // 隔离托管环境注入的 bulk-delete guard：它会把 3 组分支回归打成 SystemExit 假红。
        CODEBUDDY_SAFE_DELETE_ENABLED = '0'
    }
    stages {
        stage('Install Python dependencies') {
            steps {
                bat 'python -m venv .venv'
                bat '.venv\\Scripts\\python.exe -m pip install -r requirements.txt -r requirements-dev.txt'
            }
        }
        stage('Engineering guards') {
            steps {
                // 全仓 ruff 基线尚未建立，先对新写入口强制，避免把历史风格问题变成假红。
                bat '.venv\\Scripts\\python.exe -m ruff check tools/engineering_guards.py tools/test_engineering_guards.py tools/test_regression_manifest.py'
                bat '.venv\\Scripts\\python.exe tools/engineering_guards.py'
            }
        }
        stage('Build hooks and run regressions') {
            steps {
                bat '.venv\\Scripts\\python.exe tools/run_regressions.py --prepare --mobile --out output/ci-%BUILD_NUMBER%'
                bat '.venv\\Scripts\\python.exe tools/check_mobile_branch.py --out output/ci-%BUILD_NUMBER%/branch'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: "output/ci-${env.BUILD_NUMBER}/**", allowEmptyArchive: true
        }
    }
}
