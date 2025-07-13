FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN apk add --no-cache maven && \
    mvn clean package -DskipTests

EXPOSE 5000

ENV ORACLE_NET_WALLET_LOCATION=/app/wallet
RUN mkdir -p /app/wallet

CMD ["java", "-jar", "target/gateway-server-0.0.1-SNAPSHOT.jar"]