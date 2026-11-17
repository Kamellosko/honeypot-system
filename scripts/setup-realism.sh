#!/usr/bin/env bash
# Wygląd serwera: usuwa z maszyny to, co od razu zdradza wabik komuś, kto wpisze ps / free / ip a.
# Uruchom jako root PO setup-persona.sh, najlepiej przez SSH (nie w terminalu GNOME):
#   sudo ./scripts/setup-realism.sh
# Skrypt można uruchamiać wielokrotnie. Na końcu zrób restart (nowe ustawienia sieci, czysty swap).
#
# Co robi:
#   1. wyłącza środowisko graficzne (GNOME): tryb tekstowy, opcjonalnie usuwa pakiety,
#   2. ukrywa procesy innych użytkowników (hidepid=2): zwykły użytkownik nie zobaczy
#      sys-auditd ani Javy kolektora,
#   3. zmniejsza skłonność do swapowania i czyści zapchany swap, jeśli starcza pamięci,
#   4. adres IPv6 link-local przestaje zdradzać MAC karty (08:00:27 = VirtualBox).
#
# Zmienne (wszystkie opcjonalne):
#   HP_GUI_OFF=yes|no            wyłącz GUI (domyślnie yes)
#   HP_REMOVE_GUI_PKGS=yes|no    usuń też pakiety gdm, gnome-shell, gnome-software, evolution* (domyślnie no)
#   HP_HIDEPID=yes|no            hidepid=2 na /proc (domyślnie yes)
#   HP_SWAPPINESS=10             wartość vm.swappiness
#   HP_IPV6_PRIVACY=yes|no       ipv6.addr-gen-mode stable-privacy w NetworkManager (domyślnie yes)
#
# Nie robi (ręcznie, w hiperwizorze): MAC, DMI, rozmiar dysku i RAM, odłączenie NAT.
#
# Wycofanie hidepid: usuń linię "proc /proc ..." z /etc/fstab i wykonaj  mount -o remount,hidepid=0 /proc
# Wycofanie GUI:     systemctl set-default graphical.target  (jeśli pakiety zostały usunięte: dnf groupinstall "Server with GUI")
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Uruchom jako root:  sudo $0" >&2
  exit 1
fi

HP_GUI_OFF="${HP_GUI_OFF:-yes}"
HP_REMOVE_GUI_PKGS="${HP_REMOVE_GUI_PKGS:-no}"
HP_HIDEPID="${HP_HIDEPID:-yes}"
HP_SWAPPINESS="${HP_SWAPPINESS:-10}"
HP_IPV6_PRIVACY="${HP_IPV6_PRIVACY:-yes}"

if [ "$HP_GUI_OFF" = "yes" ]; then
  echo ">> Środowisko graficzne: tryb tekstowy"
  systemctl set-default multi-user.target
  if systemctl is-active --quiet graphical.target; then
    echo "   zatrzymuję sesję graficzną (okno VirtualBoxa przejdzie na konsolę tekstową)"
    systemctl isolate multi-user.target
  fi
  if [ "$HP_REMOVE_GUI_PKGS" = "yes" ]; then
    echo ">> Usuwanie pakietów GUI (dnf nie usunie dnf, sudo ani yum: są chronione)"
    dnf remove -y gdm gnome-shell gnome-software 'evolution*' || echo "   UWAGA: dnf nie usunął pakietów, sprawdź ręcznie: dnf remove gdm gnome-shell"
  fi
fi

if [ "$HP_HIDEPID" = "yes" ]; then
  echo ">> hidepid=2 na /proc"
  getent group proc >/dev/null || groupadd -r proc
  PROC_GID=$(getent group proc | cut -d: -f3)
  # logind musi widzieć wszystkie procesy, inaczej logowanie przestaje działać
  install -d -m 0755 /etc/systemd/system/systemd-logind.service.d
  printf '[Service]\nSupplementaryGroups=proc\n' > /etc/systemd/system/systemd-logind.service.d/hidepid.conf
  sed -i '/^proc[[:space:]]\+\/proc[[:space:]]/d' /etc/fstab
  echo "proc /proc proc defaults,hidepid=2,gid=$PROC_GID 0 0" >> /etc/fstab
  mount -o "remount,hidepid=2,gid=$PROC_GID" /proc
  systemctl daemon-reload
  systemctl restart systemd-logind
  echo "   /proc: $(findmnt -no OPTIONS /proc)"
fi

echo ">> vm.swappiness=$HP_SWAPPINESS"
printf 'vm.swappiness=%s\n' "$HP_SWAPPINESS" > /etc/sysctl.d/90-swappiness.conf
sysctl -q -p /etc/sysctl.d/90-swappiness.conf
# Wyczyść zapchany swap tylko wtedy, gdy RAM go pomieści (inaczej swapoff mógłby wywołać OOM).
swap_used=$(LC_ALL=C free -m | awk '/^Swap:/ {print $3}')
mem_avail=$(LC_ALL=C free -m | awk '/^Mem:/ {print $7}')
if [ "${swap_used:-0}" -gt 0 ]; then
  if [ "$mem_avail" -gt $((swap_used + 300)) ]; then
    echo "   czyszczę swap (${swap_used} MB w swapie, ${mem_avail} MB dostępnego RAM)"
    swapoff -a && swapon -a
  else
    echo "   swap zostaje (za mało wolnego RAM-u do bezpiecznego opróżnienia); pomoże restart"
  fi
fi

if [ "$HP_IPV6_PRIVACY" = "yes" ] && command -v nmcli >/dev/null 2>&1; then
  echo ">> IPv6 link-local bez MAC-a (stable-privacy)"
  nmcli -t -f NAME connection show | while IFS= read -r conn; do
    nmcli connection modify "$conn" ipv6.addr-gen-mode stable-privacy
  done
fi

echo
echo "Gotowe. Zrób restart:  sudo reboot"
echo "Potem sprawdź:  systemctl get-default;  free -h;  ip -6 addr show scope link;  (jako zwykły użytkownik)  ps -e | wc -l"
echo "Usługi:  systemctl is-active sysmon-collector sys-auditd smb"
