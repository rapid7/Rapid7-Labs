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
			mkdir -p Vql/release
			zip -r Vql/release/Rapid7LabsVQL.zip Vql/**/*.yaml 2> /dev/null

			echo "commit release back to project"
			git add Vql/release/Rapid7LabsVQL.zip
			git commit -m "Automatic build Rapid7LabsVQL.zip"
			git push

                '''
            }
        }

    }
}
