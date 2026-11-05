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
    }
    stages {
        stage('Install Python dependencies') {
            steps {
                bat 'python -m venv .venv'
                bat '.venv\\Scripts\\python.exe -m pip install -r requirements.txt'
            }
        }
        stage('Build hooks and run regressions') {
            steps {
                bat '.venv\\Scripts\\python.exe tools/run_regressions.py --prepare --mobile --out output/ci-%BUILD_NUMBER%'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: "output/ci-${env.BUILD_NUMBER}/**", allowEmptyArchive: true
        }
    }
}
