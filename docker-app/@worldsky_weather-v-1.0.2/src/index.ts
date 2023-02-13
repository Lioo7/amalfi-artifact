#! /usr/bin/env node

import axios from "axios";
import colors from "colors";
import { program } from "commander";
import chineseWeek from "./chineseWeek";

interface ICast {
  week: string;
  daytemp: string;
  nighttemp: string;
}

program.option("-c, --city [name]", "Add city name");
program.option("-a, --all", "Show forecast weather");
program.parse();

const options = program.opts();

if (process.argv.slice(2).length === 0) {
  program.outputHelp(colors.red);
  process.exit();
}

const WEATHER_INFO_API = "https://restapi.amap.com/v3/weather/weatherInfo";
const APP_WEATHER_KEY = "67eff89f49eee2dc498cccfd756b8ed7";
const STATUS_CODE_SUCCESS = "1";

axios
  .get(
    `${WEATHER_INFO_API}?key=${APP_WEATHER_KEY}&city=${
      options.city
    }&extensions=${options.all ? "all" : "base"}`
  )
  .then((response) => {
    if (response.status === 200) {
      // console.log(JSON.stringify(response.data));
      if (response.data.status === STATUS_CODE_SUCCESS) {
        console.log(colors.green(response.data.info));
        let data = [];
        if (options.all) {
          data = response.data.forecasts[0].casts;
        } else {
          data = response.data.lives;
        }
        data.forEach((item: ICast) => {
          item.week = chineseWeek(~~item.week);
          item.daytemp = item.daytemp + "°C";
          item.nighttemp = item.nighttemp + "°C";
        });
        console.table(data);
      } else {
        console.log(colors.red(JSON.stringify(response.data)));
      }
    } else {
      console.log(colors.red(response.statusText));
    }
  });
