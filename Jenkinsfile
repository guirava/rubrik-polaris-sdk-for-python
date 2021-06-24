pipeline {
    agent any
    stages {
        stage('Generate Docs') {
            steps {
                sh 'chmod -R 755 .'
            /**
                sh 'sudo pip3.8 install jinja2 requests'
                sh '/usr/local/bin/python3.8 ./create_docs.py'

            **/
            }
        }
        stage('Commit Docs') {
            steps {
                echo 'Commit Docs'
                sh 'git branch'
                /**
                withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'github-user', usernameVariable: 'GIT_AUTHOR_NAME', passwordVariable: 'GIT_PASSWORD']]) {
                    sh "git commit -a -m 'Documentation Update for Commit $GIT_COMMIT'"
                    sh('git push origin $BRANCH_NAME https://${GIT_AUTHOR_NAME}:${GIT_PASSWORD}@github.com/trinity-team/rubrik-sdk-for-python.git --tags -f --no-verify')
                }
                **/
            }
        }
        stage('Function Tests') {
            environment {
                // GCP credentials.
                GOOGLE_APPLICATION_CREDENTIALS = credentials('sdk-gcp-service-account')

                // Polaris credentials.
                RUBRIK_POLARIS_SERVICEACCOUNT_FILE = credentials('sdk-polaris-service-account')
                
                // Cloud resource specific information used to verify the
                // information read from Polaris.
                SDK_GCPPROJECT_FILE = credentials('sdk-test-gcp-project')
            }
            steps {
                sh 'cd tests'
                sh 'python3 -m pytest'
            }
        }
    }
    post {
        always {
            cleanWs()
        }
        success {
            echo 'successful'
        }
        failure {
            echo 'failed'
        }
        unstable {
            echo 'unstable'
        }
        changed {
            echo 'changed'
        }
    }
}

