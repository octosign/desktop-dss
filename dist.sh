#!/usr/bin/env bash

# Clear
rm -rf ./dist && mkdir ./dist

# Build the Maven project
mvn package -f pom.xml

# Copy files to dist directory
cp backend.yaml ./dist/
cp -r ./target/preparedJDK ./dist/jdk
cp -r ./target/dependency-jars ./dist/
cp ./target/octosigndss*.jar ./dist/sign.jar

# TODO: Create checksum and sign

# Create archive
XZ_OPT=-3 tar cJf tarfile.tar.xz dist/*
