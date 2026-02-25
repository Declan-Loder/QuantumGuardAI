import torch
import networkx as nx
from torch_geometric.utils import from_networkx

def generate_dataset(num_benign=50, num_attack=50):
    data_list = []

    # Benign: random graphs
    for _ in range(num_benign):
        G = nx.erdos_renyi_graph(n=20, p=0.15)
        mapping = {node: i for i, node in enumerate(G.nodes())}  # integer nodes
        G = nx.relabel_nodes(G, mapping)
        x = torch.rand((G.number_of_nodes(), 16), dtype=torch.float)
        data = from_networkx(G)
        data.x = x
        data.y = torch.tensor(0, dtype=torch.long)  # benign
        data_list.append(data)

    # Attack: star graphs
    for _ in range(num_attack):
        G = nx.Graph()
        G.add_nodes_from(range(15))
        for i in range(1, 15):
            G.add_edge(0, i)
        x = torch.rand((15, 16), dtype=torch.float)
        x[0] += 5.0  # anomaly boost
        data = from_networkx(G)
        data.x = x
        data.y = torch.tensor(1, dtype=torch.long)  # attack
        data_list.append(data)

    return data_list

if __name__ == '__main__':
    dataset = generate_dataset()
    print(f"Generated {len(dataset)} graphs")
    benign = sum(1 for d in dataset if d.y == 0)
    attack = sum(1 for d in dataset if d.y == 1)
    print(f"Benign: {benign}, Attack: {attack}")