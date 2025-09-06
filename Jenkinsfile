pipeline {
  agent any
  options { timestamps() }

  triggers {
    githubPush()
  }

  environment {
    SERVICE_NAME   = 'eureka-service'
    CONTAINER_NAME = 'consort-eureka-service'
    DOCKER_NETWORK = 'consort-infra_consort-network'
    LOGS_DIR       = '/app/logs/eureka'
    ENV_FILE       = '/var/jenkins_home/.env'
    PORT           = '8762'
    JAVA_HOME      = tool 'jdk-21'
    GRADLE_HOME    = tool 'gradle-8'
    PATH           = "${env.JAVA_HOME}/bin:${env.GRADLE_HOME}/bin:${env.PATH}"
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        script {
          env.GIT_COMMIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
          env.IMAGE_TAG    = "${env.SERVICE_NAME}:${env.GIT_COMMIT_SHORT}"
          env.IMAGE_LATEST = "${env.SERVICE_NAME}:latest"
        }
      }
    }

    stage('Load .env') {
      steps {
        script {
          def rd = { k -> sh(script: "grep -E '^${k}=' ${env.ENV_FILE} | head -n1 | cut -d= -f2- || true", returnStdout: true).trim() }
          env.SECURITY_TOKEN = rd('SECURITY_TOKEN') ?: ''
        }
      }
    }

    stage('Build core_api_dto to local maven') {
      when {
        expression {
          return fileExists('build.gradle') &&
                 sh(script: 'grep -q "core_api_dto" build.gradle', returnStatus: true) == 0
        }
      }
      steps {
        dir("${env.WORKSPACE}@core-dto") {
          sh '''
            set -e
            find . -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
            git clone https://github.com/Consort-Group-Corp/core_api_dto.git .
            chmod +x gradlew
            ./gradlew --no-daemon publishToMavenLocal
          '''
        }
      }
    }

    stage('Gradle build') {
      steps {
        sh '''
          set -e
          chmod +x gradlew
          ./gradlew --no-daemon clean build -x test
        '''
      }
    }

    stage('Archive JAR') {
      steps {
        archiveArtifacts artifacts: 'build/libs/*.jar', fingerprint: true, allowEmptyArchive: true
      }
    }

    stage('Docker build') {
      steps {
        sh '''
          set -e
          docker build -t ${IMAGE_TAG} -t ${IMAGE_LATEST} .
        '''
      }
    }

    stage('Deploy') {
      steps {
        sh '''
          set -e
          mkdir -p ${LOGS_DIR} || true
          mkdir -p /app/config/eureka || true

          # Создаем минимальный application.yml для Eureka
          cat > /app/config/eureka/application.yml << 'EOF'
server:
  port: 8762

spring:
  application:
    name: eureka-service

eureka:
  client:
    register-with-eureka: false
    fetch-registry: false
    service-url:
      defaultZone: http://localhost:8762/eureka/
  server:
    enable-self-preservation: false
    wait-time-in-ms-when-sync-empty: 0
  instance:
    hostname: localhost
    prefer-ip-address: true
    non-secure-port: 8762

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always
EOF

          docker stop ${CONTAINER_NAME} || true
          docker rm ${CONTAINER_NAME} || true

          docker run -d \
            --name ${CONTAINER_NAME} \
            --network ${DOCKER_NETWORK} \
            -p ${PORT}:${PORT} \
            -v ${LOGS_DIR}:/var/log/eureka \
            -v /app/config/eureka:/app/config \  # ← ДОБАВЛЕНО МОНТИРОВАНИЕ КОНФИГА
            -e SPRING_PROFILES_ACTIVE=dev \
            -e SERVER_PORT=${PORT} \
            -e EUREKA_INSTANCE_HOSTNAME=localhost \  # ← ИСПРАВЛЕНО НА localhost
            -e EUREKA_CLIENT_SERVICEURL_DEFAULTZONE=http://localhost:8762/eureka/ \  # ← ДОБАВЛЕНО
            -e EUREKA_INSTANCE_NON_SECURE_PORT=8762 \  # ← ДОБАВЛЕНО
            ${IMAGE_TAG}

          echo "✅ Deployed ${CONTAINER_NAME} with image ${IMAGE_TAG} on port ${PORT}"
        '''
      }
    }
  }

  post {
    success {
      echo "✅ Build & deploy success: ${env.IMAGE_TAG}"
    }
    failure {
      echo '❌ Pipeline failed — cleaning up...'
      sh '''
        docker logs --tail=200 ${CONTAINER_NAME} || true
        docker stop ${CONTAINER_NAME} || true
        docker rm ${CONTAINER_NAME} || true
        docker rmi ${IMAGE_TAG} || true
      '''
    }
    cleanup {
      cleanWs(deleteDirs: true, disableDeferredWipeout: true, notFailBuild: true)
    }
  }
}