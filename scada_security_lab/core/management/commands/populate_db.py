import random
from django.core.management.base import BaseCommand
from faker import Faker
from core.models import Device, MaintenanceLog, DiagnosticReport

class Command(BaseCommand):
    help = 'Populates the database with dummy data + SECRET TARGET for security scenarios'

    def handle(self, *args, **kwargs):
        fake = Faker()
        
        self.stdout.write("Cleaning old data...")
        # Clear existing data to avoid duplicates on multiple runs
        Device.objects.all().delete()
        MaintenanceLog.objects.all().delete()
        DiagnosticReport.objects.all().delete()

        self.stdout.write("Generating Devices...")
        
        # --- CRITICAL: SECRET TARGET DEVICE ---
        # This device is in 'Maintenance' mode and has 'is_locked_out=True'.
        # It will NOT appear on the dashboard normally due to the default filter.
        # The goal is to reveal this device using the SQL Injection vulnerability (Scenario 2).
        Device.objects.create(
            name="NUCLEAR-CORE-CONTROLLER",
            ip_address="10.0.0.99",
            location="Sector 7 (Restricted)",
            status="Maintenance",
            is_locked_out=True 
        )
        self.stdout.write(self.style.WARNING('Created SECRET Device: NUCLEAR-CORE-CONTROLLER (Hidden Target)'))
        # --------------------------------------

        # Generate 20 random standard devices
        devices = []
        for i in range(20):
            d = Device.objects.create(
                name=f"SCADA-PLC-{i}",
                ip_address=fake.ipv4_private(),
                location=fake.city(),
                # We weight 'Operational' higher so the dashboard looks normal initially
                status=random.choice(['Operational', 'Operational', 'Offline']),
                is_locked_out=False
            )
            devices.append(d)

        self.stdout.write("Generating Maintenance Logs...")
        
        # Generate 100 random logs attached to the random devices
        for _ in range(100):
            MaintenanceLog.objects.create(
                technician_name=fake.name(),
                device=random.choice(devices), 
                action=random.choice(['Reboot', 'Firmware Update', 'Valve Test', 'Pressure Check']),
            )

        self.stdout.write("Generating Diagnostic Reports...")
        
        # --- IDOR VULNERABILITY SETUP ---
        # Create a specific Sensitive Report belonging to an Admin.
        # Users should try to access this by guessing the ID (Vulnerability A).
        DiagnosticReport.objects.create(
            technician_name="Admin User",
            file_path="/protected/admin_secrets.pdf",
            content="CONFIDENTIAL: Root Password is 'supersecret123' - Do not share!"
        )

        # Generate 50 standard filler reports
        for _ in range(50):
            DiagnosticReport.objects.create(
                technician_name=fake.name(),
                file_path=f"/tmp/reports/{fake.file_name(extension='pdf')}",
                content="<xml>Standard Diagnostic Data</xml>"
            )

        self.stdout.write(self.style.SUCCESS('Successfully populated database with 100+ records and hidden targets!'))