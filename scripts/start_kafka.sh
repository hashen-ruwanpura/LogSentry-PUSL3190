#!/bin/bash

# Start Zookeeper
echo "Starting Zookeeper..."
zookeeper-server-start.sh -daemon config/zookeeper.properties

# Wait for Zookeeper to start
sleep 5

# Start Kafka
echo "Starting Kafka..."
kafka-server-start.sh -daemon config/server.properties

# Create required topics
echo "Creating Kafka topics..."
kafka-topics.sh --create --topic raw_logs --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1

echo "Kafka setup complete"