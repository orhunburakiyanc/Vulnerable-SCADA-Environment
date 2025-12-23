import random
from django.core.management.base import BaseCommand
from faker import Faker # Library to generate fake names/IPs
from core.models import Device, MaintenanceLog, DiagnosticReport

class Command(BaseCommand):
    help = 'Populates the database with 100+ records for the assignment'

    def handle(self, *args, **kwargs):
        fake = Faker()
        
        self.stdout.write("Generating Devices...")
        # Create 20 Devices
        devices = []
        for i in range(20):
            d = Device.objects.create(
                name=f"SCADA-PLC-{i}",
                ip_address=fake.ipv4_private(),
                location=fake.city(),
                status=random.choice(['Operational', 'Maintenance', 'Offline']),
                is_locked_out=random.choice([True, False])
            )
            devices.append(d)

        self.stdout.write("Generating 100 Maintenance Logs...")
        # Create 100 Logs
        for _ in range(100):
            MaintenanceLog.objects.create(
                technician_name=fake.name(),
                device=random.choice(devices),
                action=random.choice(['Reboot', 'Firmware Update', 'Valve Test', 'Emergency Stop']),
            )

        self.stdout.write("Generating Diagnostic Reports...")
        # Create 50 Reports
        for _ in range(50):
            DiagnosticReport.objects.create(
                technician_name=fake.name(),
                file_path=f"/tmp/reports/{fake.file_name(extension='pdf')}",
                content="<xml>Diagnostic Data</xml>"
            )

        self.stdout.write(self.style.SUCCESS('Successfully populated database with 100+ records!'))