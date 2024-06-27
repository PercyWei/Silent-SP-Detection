import json


class GeneralJsonRead:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None

    def read_file(self):
        try:
            with open(self.file_path, 'r') as f:
                print(f"Read json file: {self.file_path}")
                self.data = json.load(f)
        except FileNotFoundError:
            print("File not found!")
        except json.JSONDecodeError:
            print("Invalid JSON format!")

    def print_content(self, num_items=5):
        if self.data:
            self._print_dict(self.data, num_items)
        else:
            print("No data loaded. Please read the file first.")

    def _print_dict(self, data, num_items, indent=0):
        count = 0
        for key, value in data.items():
            if count >= num_items:
                break
            if isinstance(value, dict):
                print('  ' * indent + f"{key}: ")
                count += 1
                self._print_dict(value, num_items, indent + 1)
            elif isinstance(value, list):
                value_str = ' '.join(value)
                print('  ' * indent + f"{key}: {value_str}")
                count += 1
            else:
                print('  ' * indent + f"{key}: {value}")
                count += 1


if __name__ == "__main__":
    json_filepath = 'dataset/DiverseVul/diversevul_20230702.json'

    jsonRead = GeneralJsonRead(json_filepath)
    jsonRead.read_file()
    jsonRead.print_content()
