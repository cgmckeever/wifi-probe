# wifi-probe

Display the SSID probes of nearby wireless devices. Useful in wireless security awareness projects.

![](wifi-probe.gif)


# osx-probe

```
tcpdump -l -I -i mon0 -e -s 256 type mgt subtype probe-req

sudo ifconfig wlan0 down; \
sudo iw phy phy0 interface add mon0 type monitor; \
sudo ifconfig mon0 up

screen -S probe
sudo python3 wifi-probe/osx-probe.py
```

# ibeacon_scan

```
sudo hciattach /dev/ttyAMA0 bcm43xx 921600; \
sudo hciconfig hci0 down; \
sudo hciconfig hci0 up
```