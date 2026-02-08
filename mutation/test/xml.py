from lxml import etree
from rpki.xml.delta import DeltaXml
from rpki.xml.notification import NotificationXml
from rpki.xml.snapshot import SnapshotXml
import os

DEBUG = False
DELTA = True

# session_id = uuid.uuid4()
# serial = "1"

session_id = "f2eb4f5d-e085-4edb-8030-f42f38424a9f"
serial = "2"


root_dir = "./my_repo/"
root_https_url = "https://rpki.odysseus.uno/rrdp/"
rsync_root_uri = "rsync://localhost:8080/myrpki/"
target_dir = "./my_repo/rrdp/"
rrdp_target_dir = target_dir + str(session_id) + "/"
all_serial = os.listdir(rrdp_target_dir)
# print("all_serial: ", all_serial)
all_serial = [int(x) for x in all_serial]
all_serial.sort()
# print("all_serial: ", all_serial)
current_max_serial = all_serial[-1]

serial = str(current_max_serial + 1)

if DEBUG:
    os.system("rm -rf " + target_dir + "*")
    
snapshot_target_dir = target_dir + str(session_id) + "/" + str(serial)
if not os.path.exists(snapshot_target_dir):
    os.makedirs(snapshot_target_dir)

snapshot = SnapshotXml(str(session_id), serial)

for root, dirs, files in os.walk(root_dir):

    if "key" in dirs:
        dirs.remove("key")
    if "tal" in dirs:
        dirs.remove("tal")
    if "rrdp" in dirs:
        dirs.remove("rrdp")
    for file in files:
        file_path = os.path.join(root, file)
        # print("file_path: ", file_path)
        rsync_uri = file_path.replace(root_dir, rsync_root_uri)
        # print("rsync_uri: ", rsync_uri)
        snapshot.add_publish(rsync_uri, file_path)
snap_target = snapshot_target_dir + "/snapshot.xml"
snapshot.write(snap_target)

# delta.parse_snapshot(snapshot_path)
default_path = target_dir + "/" + str(session_id)
delta = DeltaXml(str(session_id), serial=serial, old_serial=str(current_max_serial), default_path=default_path)

delta.generate_delta()
delta_target = snapshot_target_dir + "/delta.xml"
delta.write(delta_target)

notification = NotificationXml(str(session_id), serial)
notification.add_snapshot(root_https_url + str(session_id) + "/" + str(serial) + "/snapshot.xml", snap_target)
notification.add_delta(root_https_url + str(session_id) + "/" + str(serial) + "/delta.xml", delta_target)
notification_target = target_dir + "/notification.xml"
print("notification_target: ", notification_target)
notification.write(notification_target)
