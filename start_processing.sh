#!/bin/bash
nohup python process_big_logs.py >> process.big.log 2> process.big.error.log &
