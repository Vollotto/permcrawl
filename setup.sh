#!/usr/bin/env bash

git submodule init;
git submodule update;
cd ./AnalysisUtils/AndroguardProject/androguard/
git checkout v2.0

touch __init__.py