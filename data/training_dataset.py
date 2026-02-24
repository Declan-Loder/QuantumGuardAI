import torch
import networkx as nx
from torch_geometric.data import Data, InMemoryDataset
from torch_geometric.utils import from_networkx

class SyntheticThreatDataset(InMemoryDataset):
    def __init__(self, root='data/processed', transform=None, pre_transform=None):
        super().__init__(root, transform, pre_transform)
        self.data, self.slices = torch.load(self.processed_paths[0])

    @property
    def raw_file_names(self):
        return ['benign_graphs.pt', 'attack_graphs.pt']

    @property
    def processed_file_names(self):
        return 'threat_data.pt'

    def process(self):
        # Create 50 benign + 50 attack graphs
        data_list = []

        # Benign: random connected graphs, low anomaly
        for _ in range(50):
            G = nx.erdos_renyi_graph(n=20, p=0.15)  # normal-ish density
            for u, v in G.edges():
                G[u][v]['weight'] = 1.0
            data = from_networkx(G)
            data.y = torch.tensor([0])  # label: benign
            data_list.append(data)

        # Attack: star-like scanning, high degree node
        for _ in range(50):
            G = nx.Graph()
            center = '192.168.1.100'
            G.add_node(center)
            for i in range(1, 15):
                ip = f'10.0.0.{i}'
                G.add_node(ip)
                G.add_edge(center, ip, weight=10.0)  # high traffic
            data = from_networkx(G)
            data.y = torch.tensor([1])  # label: attack
            data_list.append(data)

        # Save processed
        data, slices = self.collate(data_list)
        torch.save((data, slices), self.processed_paths[0])

if __name__ == '__main__':
    dataset = SyntheticThreatDataset()
    print(f"Dataset ready: {len(dataset)} graphs")
    print(f"Benign: {sum(1 for d in dataset if d.y.item() == 0)}")
    print(f"Attack: {sum(1 for d in dataset if d.y.item() == 1)}")
