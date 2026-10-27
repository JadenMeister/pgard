<!-- corpus: expect=none -->
<template>
  <div v-html="filterXSS(html)"></div>
</template>
<script setup>
import { filterXSS } from "xss";
defineProps({ html: String });
</script>
