pipeline {
    agent any

    stages {
        stage('Use Secret') {
            steps {
                // Inject secret from Jenkins Credentials
                withCredentials([string(credentialsId: 'my-secret', variable: 'API')]) {
                    // Safe use of secret
                    echo "Using secret safely"
                    
                }
            }
        }
    }
}
