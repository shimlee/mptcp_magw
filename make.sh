#!/bin/sh
make -j3;
make -j3 modules;
make -j3 modules_install;
make -j3 install;
