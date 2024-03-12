pipeline {
    agent {
        kubernetes(
            k8sAgent(
                name: 'python',
                pythonVersion: '3.11',
                defaultContainer: 'python'
            )
        )
	}
    stages {
        stage('build release vql') {
            steps {
            	sh '''
            		#!/bin/bash
             		echo "installing prerequisites"
			apt-get update
             		apt-get -y install zip

    	 		echo "build VQL release file for Velociraptor import"
			mkdir -p vql/release
			zip -r vql/release/Rapid7LabsVQL.zip vql/**/*.yaml

			echo "commit release back to project"
			git add vql/release/Rapid7LabsVQL.zip
			git commit -m "Automatic build Rapid7LabsVQL.zip"
			git push
                '''
            }
        }

    }
}
