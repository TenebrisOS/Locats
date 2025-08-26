# Locats
Locats is an open source software designed to detect nearby wireless devices connected to access points.
No access point authorization needed! 
Could be used with rooted android devices (not tested)

## Dependencies 
- Python3, Python3-pip, iw, iproute2 : ```apt install -y python3 python3-pip iw iproute2```
- Scapy : ```pip3 install scapy```
- Wireless card monitor mode compatible
- Rename ```known_device_example.json``` to ```known_devices.json``` and add your known mac addresses.

## Known Issues
If you run into "FoundError: No module named...". Make sure to install those modules using sudo.
After all it depends on each system's installation

## Features
- [x] Detecting stations (clients)
- [X] Identifying them (json file, the user should append)
- [ ] Android Root app 

## Platforms Support
- [x] Linux
- [x] (untested but should work) Android Root (termux)
- [ ] Android Root app

## Contributions
Contributions are highly encouraged and welcome. Please feel free to submit issues, pull requests, or discuss ideas. For further discussion, contact deftonish@proton.me

## Donations
- If you wish to help supporting my work, consider donating, small funds are always so caring.
- Bitcoin : ```bc1qfxg9wg97vklzselnayy0eutk5t9cpy048jmzzf```
- Ethereum : ```0x859477061053a5a6a72466fee128fbdff21a34ba```
- Solana : ```UDyMrbQh5LTBXAT3K22jRZCfnLpw4CwztiYcXBtvd4t```

## Disclaimer
This tool is designed for educational purposes only, here it demonstrates how easy it is to detect presence.I am not responsible for any misuse of my software!
## License
This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).

## Credits
This project was created and been mantained by [TenebrisOS](https://github.com/TenebrisOS)
