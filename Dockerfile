# Build stage
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

# Render provides PORT env variable
ENV PORT=8080
EXPOSE ${PORT}

# Start application with optimized JVM settings for 512MB RAM
ENTRYPOINT ["java", "-Xmx450m", "-Xms256m", "-XX:+UseG1GC", "-Dserver.port=${PORT}", "-jar", "app.jar"]
