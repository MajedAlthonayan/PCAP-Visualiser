import tkinter as tk
from tkinter import ttk, Tk
from tkinter.filedialog import askopenfilename
import pyshark, nest_asyncio, re

#stops runtime error
nest_asyncio.apply()
  
def removeAnsi(text):
    #Function which takes any text as input and removes ansi colour codes
    ansiEscape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansiEscape.sub('', text)

def parse(file_path, myFilter):
    # takes the filename and filter and returns the array of packets returned from the PCAP
    capture = pyshark.FileCapture(file_path, display_filter=myFilter)
    capture.close()
    return capture

def OnTripleClick(event):
    #Runs when the user triple clicks a packet and this displays a window containing all the information needed
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0], "text")
        if(str(item) != ""):
            #creates a seperate window to display all of the packets information

            details_window = tk.Toplevel(root)
            details_window.title("Details of Packet Number: "+ str(item))
            details_window.geometry("700x400")  

            # Filters the pcap so that only the selected packet is displayed in the new window
            filter = "frame.number == " + str(item)
            cap = parse(filename, filter)

            detailed_text = removeAnsi(str(cap[0]))

            # Create a Text widget for scrollable text
            text = tk.Text(details_window, wrap="word", width=400, height=20)  
            text.pack(side="left", padx=20, pady=20)

            # Insert the detailed text into the Text widget
            text.insert("1.0", detailed_text)

            # Create a Scrollbar for the Text widget
            scrollbar = ttk.Scrollbar(details_window, command=text.yview)
            scrollbar.pack(side="right", fill="y")

            # Configure the Text widget's yscrollcommand to the Scrollbar
            text.configure(yscrollcommand=scrollbar.set)

def filterPacket():
    #Runs when the user enters a filter in the filter box, this function outputs the results of said filter. 
    filter_text = filter_bar.get()
    tree.delete(*tree.get_children())
    displayPacket(parse(filename, filter_text))


def loadFile():
    #Runs at the start of the program and returns all the packets from the PCAP
    Tk().withdraw() 
    global filename 
    #opens the users directory so they can select the file that they would like to be analysed 
    filename = askopenfilename(filetypes=[("Pcap files", ".pcap .cap")]) 
    text_label.config(text=filename)
    displayPacket(parse(filename, ""))

def displayPacket(capture):
    #Takes a capture as parameter and returns all packets with unique sources as parents with all other packets as their children
    for packet in capture: 
        if packet.transport_layer is not None:
            if not tree.exists(packet.ip.src):
                tree.insert("", tk.END, value=(packet.ip.src), iid=packet.ip.src, tags="ip")

        else:
            if not tree.exists(packet.eth.src):
                tree.insert("", tk.END, value=(packet.eth.src), iid=packet.eth.src, tags="mac")
            
    children = tree.get_children()
    #for each of the unique packets, their children are displayed underneath them
    # displays differently depending if the packet has a transport protocol or not. 
    for child in children:
        #if the third character is : therefore it is a MAC address and not an IP address
        if child[2] == ":":
            filter = "eth.src == " + str(child)
            cap = parse(filename, filter)
            for pct in cap:
                tree.insert(child, tk.END, text=pct.number, values=("" ,pct.length, pct.frame_info.time, pct.eth.src, pct.eth.dst ), tags="mac") 
        else:
            filter = "ip.src == " + str(child)
            cap = parse(filename, filter)
            for pct in cap:
                tree.insert(child, tk.END, text=pct.number, values=("" ,pct.length, pct.frame_info.time, pct.ip.src, pct.ip.dst ), tags="ip") 
    # if a user triple clicks on a packet the onTripleClick() function is run
    tree.bind("<Triple-1>", OnTripleClick)

if __name__ == "__main__":
    #Background of the tkinter window
    root = tk.Tk()
    root.title("KAUST PCAP Visualizer")
    root.geometry("1200x600")
    
    text_label = tk.Label(root, text="")
    text_label.pack(pady=10)

    #displays the capture button to load a pcap file, this runs load_file when the button is clickde
    capture_button = tk.Button(root, text="Import PCAP", command=loadFile)
    capture_button.pack(pady=5)

    #displays the filter bar 
    filter_bar = tk.Entry(root)
    filter_bar.insert(0, "Apply a Filter ...")
    filter_bar.pack(pady=10)

    apply_button = ttk.Button(root, text="Apply Filter", command=filterPacket)
    apply_button.pack()
    filter_bar.bind("<Return>", lambda event: filterPacket())

    tree = ttk.Treeview(root, columns=("No.", "IP", "Length", "Timestamp", "Source", "IP"))
    tree.heading("#0", text="No.")
    tree.heading("#1", text="IP / MAC")
    tree.heading("#2", text="Length")
    tree.heading("#3", text="Timestamp")
    tree.heading("#4", text="Source")
    tree.heading("#5", text="Destination")
    tree.pack(padx=10, pady=10)

    infoLabel = tk.Label(root, text="Triple click on a packet for more information")
    infoLabel.pack(pady=10)
    infoLabel.configure(fg="red")

    root.mainloop()