#!/bin/bash
echo "Stopping test environment..."
kill 58678 58679 2>/dev/null
lsof -ti:8090 | xargs kill -9 2>/dev/null
lsof -ti:8091 | xargs kill -9 2>/dev/null
echo "Done!"
