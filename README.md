
## Capacitor Plugin "Torboar" developer steps.

1. git clone https://github.com/fyookball/selene3/
2. yarn install
3. cd torboar
4. yarn install
5. yarn build
6. cd ..
7. yarn add file:./torboar
8. yarn pretty
9. yarn run build
10. npx cap sync android
11. npx cap run android
12. After the emulator shows the wallet, open a new terminal and look for the output with adb logcat | grep -i "torboar"


