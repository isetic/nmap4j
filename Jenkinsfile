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
	        dir('target'){
                  echo 'creating md5sums'
                  sh 'test -f *.jar && md5sum *.jar>jar.md5sums'
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
        archive "**/target/*jar"
        archive "**/target/*md5sums"
        junit '**/surefire-reports/TEST*.xml'

      }
    }
}
