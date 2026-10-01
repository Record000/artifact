from lxml import etree
import hashlib
import base64

class DeltaXml:
    def __init__ (self, session_id, serial, old_serial, default_path, xmlns="http://www.ripe.net/rpki/rrdp", version="1"):
        self.session_id = session_id
        self.serial = serial
        self.old_serial = old_serial
        self.default_path = default_path
        self.xmlns = xmlns
        self.root = etree.Element("delta")
        self.root.set("xmlns", xmlns)
        self.root.set("version", version)
        self.root.set("session_id", session_id)
        self.root.set("serial", serial)
    
    def add_publish_element(self, uri, base64_value, hash_value=None):
        publish = etree.SubElement(self.root, "publish")
        publish.set("uri", uri)
        if hash_value:
            publish.set("hash", hash_value)
        publish.text = base64_value
    
    def add_withdraw_element(self, uri, hash_value):
        withdraw = etree.SubElement(self.root, "withdraw")
        withdraw.set("uri", uri)
        withdraw.set("hash", hash_value)
    
    def calculate_base64(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
            base64_value = base64.b64encode(data).decode()
            return base64_value
        
    def calculate_hash(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
            hash = hashlib.sha256(data).hexdigest()
            return hash

    def parse_snapshot(self, snapshot_path):
        tree = etree.parse(snapshot_path)
        root = tree.getroot()
        # print("root: ", root)
        base_tag = "{" + self.xmlns + "}" + "publish"
        publish_elements = {}
        for publish in root.getchildren():
            if publish.tag != base_tag:
                exit("Error: publish tag not found")
            uri = publish.get("uri")
            base64_value = publish.text
            # print("uri: ", uri)
            # print("base64_value: ", base64_value)
            publish_elements[uri] = base64_value
        return publish_elements

    def parse_old_snapshot(self):
        old_snapshot_path = self.default_path + "/" + self.old_serial + "/snapshot.xml"
        return self.parse_snapshot(old_snapshot_path)

    def parse_new_snapshot(self):
        new_snapshot_path = self.default_path + "/" + self.serial + "/snapshot.xml"
        return self.parse_snapshot(new_snapshot_path)
    
    def add_publish(self, uri, file_path):
        # hash_value = self.calculate_hash(file_path)
        base64_value = self.calculate_base64(file_path)
        self.add_publish_element(uri, base64_value)
    
    def generate_delta(self):
        old_snapshot = self.parse_old_snapshot()
        new_snapshot = self.parse_new_snapshot()
        for key in new_snapshot.keys():
            if key in old_snapshot.keys():
                if new_snapshot[key] != old_snapshot[key]:
                    print("key: ", key)
                    decoded_file = base64.b64decode(old_snapshot[key])
                    old_file_hash = hashlib.sha256(decoded_file).hexdigest()
                    print("old_file_hash: ", old_file_hash)
                    self.add_publish_element(key, new_snapshot[key], old_file_hash)
            else:
                self.add_publish_element(key, new_snapshot[key])

        withdraw_elements = set(old_snapshot.keys()) - set(new_snapshot.keys())
        for element in withdraw_elements:
            decoded_file = base64.b64decode(old_snapshot[element])
            old_file_hash = hashlib.sha256(decoded_file).hexdigest()
            self.add_withdraw_element(element, old_file_hash)
    
    
    def write(self, file_path):
        tree = etree.ElementTree(self.root)
        tree.write(file_path, encoding="utf-8", xml_declaration=False, pretty_print=True)