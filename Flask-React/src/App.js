
import React, { Component } from "react";
import ReactDOM from "react-dom";
import logo from './logo.svg';
import './App.css';
import axios from 'axios';
import Cropper from "./components/cropper";
import stock from '../src/STOCK.png'


class App extends Component{ 
  constructor(props)
  {    super(props)    
    this.state = 
    {      
      selectedFile: null   
    } 
    this.fileSelectedHandler = this.fileSelectedHandler.bind(this)

  }

  fileSelectedHandler(event) {
    console.log("Selected")
    this.setState({
      selectedFile : URL.createObjectURL(event.target.files[0])
    })
  }
  
  fileUploadHandler(){
    console.log("Entered")
    }
    // const fd=new FormData();
    //fd.append('image',this.state.selectedFile)
    //axios.post("http://127.0.0.1:5000/",fd)

    
render(){
  return(
    <div>
      <input type="file" onChange={this.fileSelectedHandler}/>
      { <img src={this.state.selectedFile}></img> }
      <div>
            <Cropper src={stock}></Cropper>
      </div>
    </div>
  )};}

export default App;

