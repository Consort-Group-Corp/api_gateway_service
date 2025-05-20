FROM openjdk:21-jdk-slim
WORKDIR /app
RUN apt-get update && apt-get install -y wget
COPY build/libs/*.jar app.jar
EXPOSE 8085
ENTRYPOINT ["java", "-jar", "-Dspring.config.location=classpath:/,file:/app/config/application.yml", "app.jar"]