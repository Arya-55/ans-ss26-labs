import re
import numpy as np
import matplotlib.pyplot as plt


TCP_MARKER = "===== TCP =====\n"
UDP_MARKER = "===== UDP =====\n"
MARKER_LEN = len(TCP_MARKER)

def _parse_tcp_result(tcp_str):
    throughput_strs = re.findall(r" \d+\.\d+ Mbits/sec", tcp_str)
    throughputs = [float(s.split(" ")[1]) for s in throughput_strs]
    return throughputs


def _parse_udp_result(udp_str):
    server_reports = "\n".join(re.findall(r"\[  1\] Server Report:\n.*\n.*\n.*\n", udp_str))
    print(server_reports)    

    throughput_strs = re.findall(r" \d+\.\d+ Mbits/sec", server_reports)
    throughputs = [float(s.split(" ")[1]) for s in throughput_strs]
    print("=>", throughputs)

    loss_strs = re.findall(r"\d+(?:\.\d+)?%", server_reports)
    losses = [float(s[:-1]) for s in loss_strs]
    print("=>", losses)

    return throughputs, losses


def _get_results(filename):
    results = {}

    with open(filename, "r") as f:
        tmp = f.read()
        tcp_str = tmp[tmp.find(TCP_MARKER) + MARKER_LEN : tmp.find(UDP_MARKER)]
        results["tcp"] = _parse_tcp_result(tcp_str)

        print(10 * "#", "\n")
        
        results["udp"] = {}
        udp_str = tmp[tmp.find(UDP_MARKER) + MARKER_LEN:]
        results["udp"]["throughput"], results["udp"]["loss"] = _parse_udp_result(udp_str)

    return results


print("=== SP ROUTING ===")
sp_results = _get_results("sp_result.txt")

print("=== FT ROUTING ===")
ft_results = _get_results("ft_result.txt")


# Plot TCP results
bar_labels = ["Single\nh21 -> h35", "Simultaneous\nI) h21 -> h35", "Simultaneous\nII) h22 -> h36"]
x = np.arange(len(bar_labels))
width = 0.25

fig = plt.figure()

plt.grid(axis="y", linestyle="--", alpha=0.7, zorder=0)
plt.bar(x - width, [15] * 3, width, label="Max Potential", zorder=3)
plt.bar(x, ft_results["tcp"], width, label="Two Level", zorder=3)
plt.bar(x + width, sp_results["tcp"], width, label="Shortest Path", zorder=3)

plt.xticks(x, bar_labels)
plt.yticks(range(16))
plt.ylim(0,20)

plt.ylabel("Throughput [Mbps]")
plt.title("Comparison of TCP-Connection Throughput (via iperf)")
plt.legend()

fig.savefig("tcp_comparison.png", dpi=300, bbox_inches="tight")

# Plot UDP results
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

# plot througput like above
ax1.grid(axis="y", linestyle="--", alpha=0.7, zorder=0)
ax1.bar(x - width, [15] * 3, width, label="Max Potential", zorder=3, color="tab:blue")
ax1.bar(x, ft_results["udp"]["throughput"], width, label="Two Level", zorder=3, color="tab:orange")
ax1.bar(x + width, sp_results["udp"]["throughput"], width, label="Shortest Path", zorder=3, color="tab:green")

ax1.set_xticks(x, bar_labels)
ax1.set_yticks(range(16))
ax1.set_ylim(0,20)

ax1.set_ylabel("Throughput [Mbps]")
ax1.set_title("Throughput")
ax1.legend()

# plot losses
ax2.grid(axis="y", linestyle="--", alpha=0.7, zorder=0)
ax2.bar(x - width/2, ft_results["udp"]["loss"], width, label="Two Level", zorder=3, color="tab:orange")
ax2.bar(x + width/2, sp_results["udp"]["loss"], width, label="Shortest Path", zorder=3, color="tab:green")

ax2.set_xticks(x, bar_labels)
ax2.yaxis.tick_right()
ax2.yaxis.set_label_position("right")
ax2.set_ylim(0,100)

ax2.set_ylabel("Loss [%]")
ax2.set_title("Packet Loss")
ax2.legend()

fig.suptitle("Comparison of UDP-Connection  (via iperf)")
fig.savefig("udp_comparison.png", dpi=300, bbox_inches="tight")
