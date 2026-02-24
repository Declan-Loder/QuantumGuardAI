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
        return []  # No raw files needed

    @property
    def processed_file_names(self):
        return 'threat_data.pt'

    def process(self):
        data_list = []

        # Benign graphs: random connected, low anomaly
        for _ in range(50):
            G = nx.erdos_renyi_graph(n=20, p=0.15)
            # Add dummy node features (important!)
            node_features = torch.rand((G.number_of_nodes(), 16), dtype=torch.float)  # 16-dim random
            data = from_networkx(G)
            data.x = node_features  # Attach features
            data.y = torch.tensor([0], dtype=torch.long)  # benign
            data_list.append(data)

        # Attack graphs: star-like scanning, high degree center
        for _ in range(50):
            G = nx.Graph()
            center = 0  # use integer nodes for simplicity
            G.add_node(center)
            for i in range(1, 15):
                G.add_node(i)
                G.add_edge(center, i)
            # Dummy features
            node_features = torch.rand((G.number_of_nodes(), 16), dtype=torch.float)
            # Boost center node feature to simulate anomaly
            node_features[center] += 5.0
            data = from_networkx(G)
            data.x = node_features
            data.y = torch.tensor([1], dtype=torch.long)  # attack
            data_list.append(data)

        data, slices = self.collate(data_list)
        torch.save((data, slices), self.processed_paths[0])

if __name__ == '__main__':
    dataset = SyntheticThreatDataset()
    print(f"Dataset ready: {len(dataset)} graphs")
    print(f"Benign: {sum(1 for d in dataset if d.y.item() == 0)}")
    print(f"Attack: {sum(1 for d in dataset if d.y.item() == 1)}")
