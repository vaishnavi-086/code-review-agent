// leap year 

#include <iostream>
using namespace std;

int main(){
    int year;
    cout<<"enter a year:";
    cin>>year;

    if(year % 400 == 0){
        cout<<"its a  leap year";
    }
    else if(year % 100==0){
        cout<<"its not a leap year";
    }
    else if(year % 4 == 0){
        cout<<"leap year";
    }
    else{
        cout<<"not leap year";
    }
    return 0;
}



