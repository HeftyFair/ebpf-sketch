
# init netns
sudo ip netns add ns1


# load xdp program
sudo ip link set dev eth1 xdp obj xdp_prog.o sec xdp_pass

# dump xdp map by command


# load xdp program in netns
sudo ip netns exec ns1 ip link set dev eth1 xdp obj xdp_prog.o sec xdp_pass



# add a veth pair in ns1 and root
sudo ip link add veth0 type veth peer name veth1