from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / 'TelegramShare/ShareAttachmentAcquisition.swift').read_text()
fixture = Path(__file__).with_name('ShareAttachmentAcquisitionTests.swift').read_text().replace('__SOURCE__', source)

with tempfile.TemporaryDirectory(prefix='share-attachment-acquisition-') as directory:
    directory = Path(directory)
    (directory / 'Package.swift').write_text('''// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "ShareAttachmentAcquisition", platforms: [.macOS(.v10_13)], targets: [.testTarget(name: "ShareAttachmentAcquisitionTests", path: "Tests")])
''')
    (directory / 'Tests').mkdir()
    (directory / 'Tests/ShareAttachmentAcquisitionTests.swift').write_text(fixture)
    raise SystemExit(subprocess.run(['swift', 'test', '--package-path', str(directory), '--disable-sandbox', '--jobs', '4']).returncode)

