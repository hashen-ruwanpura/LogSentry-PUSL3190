@echo off
REM filepath: c:\Users\MSii\Desktop\Threat-Detection-and-Notification-Platform-by-Analyzing-Logs-of-Apache-and-MySQL-servers-\scripts\start_kafka.bat

echo Starting Zookeeper...
start "Zookeeper" cmd /c "cd C:\Kafka_2.13-3.8.1 && bin\windows\zookeeper-server-start.bat config\zookeeper.properties"

echo Waiting for Zookeeper to start...
timeout /t 10

echo Starting Kafka...
start "Kafka" cmd /c "cd C:\Kafka_2.13-3.8.1 && bin\windows\kafka-server-start.bat config\server.properties"

echo Waiting for Kafka to initialize...
timeout /t 15

echo Creating Kafka topics...
cd C:\Kafka_2.13-3.8.1
bin\windows\kafka-topics.bat --create --topic raw_logs --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1 --if-not-exists

echo Kafka setup complete