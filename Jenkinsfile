pipeline {
    agent any
    tools {
        maven 'maven-3.3.9'
        //jdk 'jdk8'
    }
    stages {
      	stage ('Checkout'){
          steps {
            checkout scm
          }
      	}
        stage ('Build') {
            steps {
                //	sh 'mvn clean install -Dmaven.test.failure.ignore=true -DcreateChecksum=true'
		sh "./gradlew clean build"
	        dir('./build/libs'){
                  echo 'creating md5sums'
                  sh 'test -f org.nmap4j-1.0.4.jar && md5sum *.jar>jar.md5sums'
                }
            }
        }
        stage ('publish'){
            steps {
	      echo 'env.BRANCH_NAME...' + env.BRANCH_NAME
		echo 'TODO'
            }
        }
    }
    post {
      always {
        archive "**/target/**/*jar"
        archive "**/build/**/*jar"
        archive "**/target/**/*md5sums"
        archive "**/build/**/*md5sums"
        junit '**/TEST*.xml'

      }
    }
}
