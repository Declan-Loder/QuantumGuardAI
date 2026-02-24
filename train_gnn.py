import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from quantumguard.models.gnn import GNNTthreatModel
from data.training_dataset import SyntheticThreatDataset

# Config
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
batch_size = 32
epochs = 50
lr = 0.001

# Load dataset
dataset = SyntheticThreatDataset()
dataset = dataset.shuffle()
train_size = int(0.8 * len(dataset))
train_dataset = dataset[:train_size]
test_dataset = dataset[train_size:]

train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=batch_size)

# Model (use your existing class)
model = GNNTthreatModel({
    'type': 'graphsage',
    'hidden_channels': 128,
    'num_layers': 3,
    'dropout': 0.2,
    'out_channels': 2  # binary classification: benign vs threat
}).to(device)

optimizer = torch.optim.Adam(model.parameters(), lr=lr)
criterion = torch.nn.CrossEntropyLoss()

def train():
    model.train()
    total_loss = 0
    for batch in train_loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        out = model(batch.x, batch.edge_index)
        loss = criterion(out, batch.y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    return total_loss / len(train_loader)

def test():
    model.eval()
    correct = 0
    for batch in test_loader:
        batch = batch.to(device)
        out = model(batch.x, batch.edge_index)
        pred = out.argmax(dim=1)
        correct += (pred == batch.y).sum().item()
    return correct / len(test_dataset)

print("Starting training...")
for epoch in range(1, epochs + 1):
    loss = train()
    acc = test()
    print(f'Epoch: {epoch:03d}, Loss: {loss:.4f}, Test Acc: {acc:.4f}')

# Save trained model
torch.save(model.state_dict(), 'models/trained_gnn.pt')
print("Training complete. Model saved to models/trained_gnn.pt")
