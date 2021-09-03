

Prerequisites
------------

 - PA-DFD tool is written in Python, which can be run by interpreter that is Python 3.7 or later. Python 3.7 can be dowmload from (https://www.python.org/downloads/) 
 
 - Download draw.io from (https://about.draw.io/integrations/#integrations_offline) for drawing DFDs
 
 - Draw.io does not come with dedicated libraries for DFDs, download libraries for DFD from  (https://github.com/michenriksen/drawio-threatmodeling)



Usage
------------

1- Draw your DFD by using draw.io

2- Export xml file of DFD from draw.io 
 
3- Clone the [GitHub repository](https://github.com/alshareef-hanaa/PA-DFD):

    $ git clone https://github.com/alshareef-hanaa/PA-DFD.git
    
4- Go into directory where the script(dfd_to_padfd.py) and the xml file of DFD, which you have exported in steps 2. To run the  the script(dfd_to_padfd.py) from the terminal, you need to provide the file names of csv file for DFD, csv file for PA-DFD and xml file for PA-DFD as arguments, use the following command: 

    $ python dfd_to_padfd.py "the name of DFD xml file" "the name of DFD csv file" 
      "the name of PA-DFD csv file" "the name of PA-DFD xml file" 
 
5- Deployment: import the PA-DFD xml file in draw.io and modify the layout of your diagram



Example
------------

Amazon_dfd_in_comp.drawio contains subpart of the case study which is Amazon level-0 DFD. This example focus on the usage hotspot. The DFD is exported as xml file from drawio tool and called Amazon_dfd_in_comp.xml. From the directory where we have the script(dfd_to_padfd.py) and aforementioned file, we have run the following:

     $ python dfd_to_padfd.py Amazon_dfd_in_comp.xml  Amazon_dfd_in_comp.csv
       Amazon_padfd_in_comp.csv Amazon_padfd_in_comp.xml 

where the third, fourth and fifth arguments are the name of DFD csv file, PA-DFD csv file and PA-DFD xml file, respectively.
After this terminated successfully, we got PA-DFD in format of xml file (Amazon_dfd_in_comp.xml). In order to get PA-DFD diagram, we have imported/opened Amazon_padfd_in_comp.xml in drawio. Finally, we have modified the layout of PA-DFD to have readable diagram.
