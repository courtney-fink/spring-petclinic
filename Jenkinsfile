def label = "mypod-${UUID.randomUUID().toString()}"
def serviceaccount = "jenkins-admin"
podTemplate(label: label, serviceAccount: serviceaccount,
    containers: [containerTemplate(name: 'python', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/python', ttyEnabled: true, command: 'cat'),
    containerTemplate(name: 'curl', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/curl:2.0', ttyEnabled: true, alwaysPullImage: true, command: 'cat'),
    containerTemplate(name: 'git-secrets', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/git-secrets:0.1', ttyEnabled: true, alwaysPullImage: true, command: 'cat'),
    containerTemplate(name: 'jmeter', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/jmeter:5.4.3', ttyEnabled: true, command: 'cat'),
    containerTemplate(name: 'maven', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/maven:3.8-openjdk-11', ttyEnabled: true, command: 'cat',resourceRequestCpu: '150m',resourceLimitCpu: '4000m',resourceRequestMemory: '100Mi',resourceLimitMemory: '7000Mi'),
    containerTemplate(name: 'kubectl', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/docker-kubectl:19.03-alpine', ttyEnabled: true, command: 'cat',
    volumes: [secretVolume(secretName: 'kube-config', mountPath: '/root/.kube')]),
    containerTemplate(name: 'zap', image: 'localhost:32121/root/docker_registry/aiindevops.azurecr.io/zap2docker:log4j-2.17.1', privileged: true, ttyEnabled: true, command: 'cat')],          
      imagePullSecrets: ['gcrcred'],
        yaml: """
        spec:
          containers:
          - name: trivy
            image: localhost:32121/root/docker_registry/aiindevops.azurecr.io/trivy:0.9.2
            tty: true
            command: ["/bin/sh"]
          - name: kaniko
            image: localhost:32121/root/docker_registry/aiindevops.azurecr.io/kaniko:v1.3.0-debug
            imagePullPolicy: IfNotPresent
            resources:
              limits:
                cpu: 600m
                memory: 1000Mi
              requests:
                cpu: 60m
                memory: 200Mi
            command:
            - /busybox/cat
            tty: true
            volumeMounts:
            - name: my-secret
              mountPath: /kaniko/.docker
          volumes:
          - name: my-secret
            projected:
              sources:
              - secret:
                  name: gitlabcred
                  items:
                    - key: .dockerconfigjson
                      path: config.json
  
    """
    )
{
  
    node(label) {
        def GIT_URL= 'https://abf5f45dfcdac4059958d488fc5fdc75-1885537743.us-east-2.elb.amazonaws.com/gitlab/Courtney/tcfapppython'
        def GIT_CREDENTIAL_ID ='gitlab'
        def GIT_BRANCH='master'

        /*** Kuberenetes  ***/
        def K8S_DEPLOYMENT = 'mongopy'   
                   
     try {
       
        stage('Git Checkout') {
            git branch: GIT_BRANCH, url: GIT_URL,credentialsId: GIT_CREDENTIAL_ID
            def Nap = load "${WORKSPACE}/git_scan_nonallowed.groovy"
            def Ap = load "${WORKSPACE}/git_scan_allowed.groovy"
            def function = load "${WORKSPACE}/JenkinsFunctions_Python.groovy"
              
            // Below two lines are to publish last commited user name and email into jenkins console logs
            sh 'GIT_NAME=$(git --no-pager show -s --format=\'%an\' $GIT_COMMIT)'
            sh 'GIT_EMAIL=$(git --no-pager show -s --format=\'%ae\' $GIT_COMMIT)'
            
            stage('Git Secret') {
                container('git-secrets') {
                    Nap.nonAllowedPattern()
                    Ap.AllowedPattern()
                    sh 'git secrets --scan'
                    }    
            } // End of Git Secret Stage
            stage('Dependency Check') {
              sh '''cd ${WORKSPACE}/
              mkdir reports_dir
              ls -lrt'''
              container('maven') {
                  try{
                      sh '''
                      set -x
                      mvn org.owasp:dependency-check-maven:check -D assemblyAnalyzerEnabled=false -D format=ALL -D dataDirectory=/usr/share/nvd -D autoUpdate=true -Dmaven.artifact.threads=5 -Dmaven.wagon.http.pool=false
                      '''
                  }catch(Exception e){
                      sh '''
                      set +e
                      for i in 1 2 3
                      do
                          echo "Looping ... number $i"
                          mvn org.owasp:dependency-check-maven:check -D assemblyAnalyzerEnabled=false -D format=ALL -D dataDirectory=/usr/share/nvd -D autoUpdate=true -Dmaven.artifact.threads=5 -Dmaven.wagon.http.pool=false
                          if [ "$?" -eq 0 ]; then
                          echo "depedendency check is successfull "
                          break
                          elif  [ "$i" -lt 3 ]; then
                          echo "failed to connect to nvd and retrying"
                          continue
                          elif [ "$i" -eq 3 ]; then
                          echo "failed to connect to nvd after 3 tries "
                          exit 1
                          fi
                      done
                      '''
                  }
                  dependencyCheckPublisher canComputeNew: false, defaultEncoding: '', healthy: '', pattern: '', unHealthy: ''
                  sh 'cp -r target/dependency-check-report.html target/dependency-check-report-${BUILD_ID}.html'
                  archiveArtifacts allowEmptyArchive: true, artifacts: 'target/dependency-check-report.html', onlyIfSuccessful: true
                  sh 'apt-get update -y'
                  sh 'apt-get install -y util-linux pciutils usbutils coreutils binutils findutils grep gawk'
                  sh '''
                  high_count=$(grep -i -c HIGH target/dependency-check-report-${BUILD_ID}.html)                      
                  critical_count=$(grep -i -c CRITICAL target/dependency-check-report-${BUILD_ID}.html)                 
                  if [ $high_count -gt 100 -a $critical_count -gt 100 ]
                  then
                  echo "The Application has Vulnerabilities"
                  exit 1
                  else
                  echo "The Application has no Vulnerabilities"
                  fi
                  '''
                  sh 'mv ${WORKSPACE}/target/dependency-check-report.html reports_dir/dependency-check-report.html'
              }
            } // End of Dependency Check Stage
            
            stage('Build Project') {
                container('python') {
                  function.buildMethod()
                  //sh 'nosetests -v'
                }
            } // End of Build Project Stage
            
            stage('MongoDB Instance Creation') {
                            container('kubectl') {
                                try{
                                    sh("kubectl get deployment/mongopy -n ethan")
                                        if(true){
                                            sh ("kubectl set image deployment/${K8S_DEPLOYMENT} ${K8S_DEPLOYMENT}=${GCR_HUB_ACCOUNT}/${GCR_HUB_ACCOUNT_NAME}/${GCR_HUB_REPO_NAME}/mongo:3.4 -n ethan")
                                        }
                                    } catch(e){
                                        sh("kubectl apply -f mongo.yaml -n ethan")
                                        echo "deploying"
                                    }
                                sh ("kubectl get pods | grep mongopy")
                                sh ("kubectl get svc mongopy -n ethan")
                            }
            } // End of MongoDB Instance Creation Stage
            
            stage('Unit Test') {
                  container('python') {
                      function.testMethod()
                      sh 'sleep 40'
                  }
            } // End of Unit Test Stage
            stage('SonarQube Analysis') {
                withCredentials([usernamePassword(credentialsId: 'SONAR', passwordVariable: 'PASSWORD', usernameVariable: 'USERNAME')]){
                    container('curl') {
                        sh '''
                            export SONAR_QG_NAME='python_QG'
                            SONAR_HOST_URL="http://sonar.ethan.svc.cluster.local:9001/sonar"
                            echo "Creating SonarQube Gateway"
                            curl -u ${USERNAME}:${PASSWORD} -X POST "${SONAR_HOST_URL}/api/qualitygates/create?name=$SONAR_QG_NAME"
                            '''
                        sh '''#!/bin/bash
                            SONAR_HOST_URL="http://sonar.ethan.svc.cluster.local:9001/sonar"
                            export SONAR_QG_NAME='python_QG'
                            curl -u ${USERNAME}:${PASSWORD} "${SONAR_HOST_URL}/api/qualitygates/show?name=$SONAR_QG_NAME" > qualitygate.json
                            curl_cmd=( curl -u ${USERNAME}:${PASSWORD} -k -X POST ${SONAR_HOST_URL}/api/qualitygates/ )
                            url="create_condition"
                            QG_ID=$( jq -r ".id" qualitygate.json )
                            gateMetrics=(
                                        coverage,LT,80
                                        blocker_violations,GT,10
                                        critical_violations,GT,9
                                        major_violations,GT,0
                                        )
                            query_fmt="gateId=%s&metric=%s&op=%s&error=%s"
                            for metric in "${gateMetrics[@]}"; do
                            IFS=, read -r m o e <<< "$metric"
                            printf -v query "$query_fmt" "$QG_ID" "$m" "$o" "$e"
                            "${curl_cmd[@]}""${url}?${query}"
                            done
                            '''
                        sh '''
                            export SONAR_PROJECT_NAME='TcfAppPython'
                            export SONAR_PROJECT_KEY='TcfAppPython'
                            export SONAR_QG_NAME='python_QG'
                            SONAR_HOST_URL="http://sonar.ethan.svc.cluster.local:9001/sonar"
                            curl -u ${USERNAME}:${PASSWORD} -k -X POST "${SONAR_HOST_URL}/api/projects/create?project=$SONAR_PROJECT_KEY&name=$SONAR_PROJECT_NAME"
                            curl -u ${USERNAME}:${PASSWORD} -k "${SONAR_HOST_URL}/api/qualitygates/show?name=$SONAR_QG_NAME" > qualitygate.json
                            QG_ID=$( jq -r ".id" qualitygate.json )
                            curl -u ${USERNAME}:${PASSWORD} -k -X POST "${SONAR_HOST_URL}/api/qualitygates/select?gateId=$QG_ID&projectKey=$SONAR_PROJECT_KEY"
                            Gateway_file="./sonar-gateway.properties"
                            Coverage=`cat $Gateway_file | grep -i 'Coverage' | cut -f2 -d'='`
                            Blocker=`cat $Gateway_file | grep -i 'Blocker' | cut -f2 -d'='`
                            Critical=`cat $Gateway_file | grep -i 'Critical' | cut -f2 -d'='`
                            Major=`cat $Gateway_file | grep -i 'Major' | cut -f2 -d'='`
                            cat qualitygate.json | jq -r ".conditions[].id" > cgid.txt
                            cid=$(head -n 1 cgid.txt)
                            echo "Updating Sonar Qube gateway"
                            curl -u ${USERNAME}:${PASSWORD} -k -X POST "${SONAR_HOST_URL}/api/qualitygates/update_condition?gateId=$QG_ID&id=$cid&metric=coverage&op=LT&error=$Coverage"
                            bvid=$(sed -n '2p' cgid.txt)
                            curl -u ${USERNAME}:${PASSWORD} -k -X POST "${SONAR_HOST_URL}/api/qualitygates/update_condition?gateId=$QG_ID&id=$bvid&metric=blocker_violations&op=GT&error=$Blocker"
                            cvid=$(sed -n '3p' cgid.txt)
                            curl -u ${USERNAME}:${PASSWORD} -k -X POST "${SONAR_HOST_URL}/api/qualitygates/update_condition?gateId=$QG_ID&id=$cvid&metric=critical_violations&op=GT&error=$Critical"
                            mvid=$(sed -n '4p' cgid.txt)
                            curl -u ${USERNAME}:${PASSWORD} -k -X POST "${SONAR_HOST_URL}/api/qualitygates/update_condition?gateId=$QG_ID&id=$mvid&metric=major_violations&op=GT&error=$Major"
                            echo "Displaying Existing Sonar Issues"
                            '''
                    }
                    container('maven') {
                        sh '''
                        apt-get update -y
                        apt-get install -y nodejs
                        '''
                        withSonarQubeEnv('SonarQube') {
                            println('Sonar Method enter');
                                    function.sonarMethod()
                            echo "Access the SonarQube URL from the Platform Dashboard tile"
                                    sh '''
                                    sleep 30
                                    export SONAR_PROJECT_NAME='TcfAppPython'
                                    curl -k -u ${USERNAME}:${PASSWORD} "${SONAR_HOST_URL}/api/measures/component?metricKeys=critical_violations,coverage,major_violations,blocker_violations&component=$SONAR_PROJECT_NAME" > sonar-result.json
                                    cat sonar-result.json
                                    '''
                        }
                        timeout(time: 1, unit: 'HOURS')
                        {
                            def qg = waitForQualityGate()
                            if (qg.status != 'OK') {
                                error "Pipeline aborted due to quality gate failure: ${qg.status}"
                            }
                        }
                    }
                }
            } // End of SonarQube Analysis Stage
            stage('Jacoco Code Coverage'){
                jacoco()
            } // End of Jacoco Code Coverage

        } // End of Git Checkout Stage
  
        currentBuild.result = 'SUCCESS'
        echo "RESULT: ${currentBuild.result}"
        echo "Finished: ${currentBuild.result}"
                
        } catch (Exception err) {
        currentBuild.result = 'FAILURE'
        echo "RESULT: ${currentBuild.result}"
        echo "Finished: ${currentBuild.result}"
        }             
      
     
    } // End of node
       
}
